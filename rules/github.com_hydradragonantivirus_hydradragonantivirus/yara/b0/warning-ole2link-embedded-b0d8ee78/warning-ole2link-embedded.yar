rule warning_ole2link_embedded {
  meta:
    is_exploit = true
    is_warning = false
    is_feature = false
    rank       = 1
    revision   = "3"
    date       = "September 12 2017"
    author     = "David Cannings"
    copyright  = "source https://github.com/nccgroup/Cyber-Defence/blob/master/Technical%20Notes/Office%20zero-day%20(April%202017)/2017-04%20Office%20OLE2Link%20zero-day%20v0.4.md"
    tlp        = "white"
    sigtype    = "cryptam_warning"
    desc       = "Office OLE2Link unsafe content such as remote risky content"

  strings:
        $header_rtf    = "{\\rt" nocase
    $header_office = { D0 CF 11 E0 }
    $header_xml    = "<?xml version=" nocase wide ascii

            $embedded_object   = "\\object" nocase
    $embedded_objdata  = "\\objdata" nocase
    $embedded_ocx      = "\\objocx" nocase
    $embedded_objclass = "\\objclass" nocase
    $embedded_oleclass = "\\oleclsid" nocase

        $embedded_axocx     = "<ax:ocx" nocase wide ascii
    $embedded_axclassid = "ax:classid" nocase wide ascii

        $embedded_root_entry = "Root Entry" wide
    $embedded_comp_obj   = "Comp Obj" wide
    $embedded_obj_info   = "Obj Info" wide
    $embedded_ole10      = "Ole10Native" wide

    $data0 = "00000300-0000-0000-C000-000000000046" nocase wide ascii
    $data1 = { 00 03 00 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
    $data2 = "OLE2Link" nocase wide ascii
    $data3 = "4f4c45324c696e6b" nocase wide ascii
    $data4 = "StdOleLink" nocase wide ascii
    $data5 = "5374644f6c654c696e6b" nocase wide ascii

  condition:
        1 of ($header*) and 1 of ($embedded*)
    and (1 of ($data*))
}