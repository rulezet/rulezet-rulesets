rule sig_20160309_e41982113ecc0065ae67324116c5e8a3 {
  meta:
    description = "datamaliciousorder - file 20160309_e41982113ecc0065ae67324116c5e8a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "baa47bf0fe474e4386a9a4cc0133da17ea00e324b4524463f8fb5f2cd24db6fc"

  strings:
    $s1  = "progress[height](iframe, globalEventContext + fragment + fragment + head + dataUser + compile + removeEventListener + window + p" ascii
    $s2  = "progress[height](iframe, globalEventContext + fragment + fragment + head + dataUser + compile + removeEventListener + window + p" ascii
    $s3  = "operator[linear + hasContent + onabort] = ((keys | 1) & (keys * 0));" fullword ascii
    $s4  = "ajaxExtend[processData + match + elements]();" fullword ascii
    $s5  = "finish[close](modified.rscriptTypeMasked(), (nType / 50), ((keys * 1) * (nType / 1)));" fullword ascii
    $s6  = "progress = rootjQuery[hookFn + getClientRects + match + collection][removeData + stopOnFalse + dataType + collection](Expr + gre" ascii
    $s7  = "progress = rootjQuery[hookFn + getClientRects + match + collection][removeData + stopOnFalse + dataType + collection](Expr + gre" ascii
    $s8  = "grep = \"XML2\", attrId = \"WSc\", processData = \"o\", reverse = 7, stopOnFalse = \"te\", rfocusable = \"Exp\";" fullword ascii
    $s9  = "rootjQuery = (((3 & overflowY) + (1 | overflowY)), ((Math.pow((12 + nType), (2 + nType)) - (106 | cacheURL)), this));" fullword ascii
    $s10 = "ajaxExtend[tabIndex + Sizzle + cur + rsubmittable + removeEventListener + isPlainObject](modified, ((keys * 2) + (nType ^ 0)));" fullword ascii
    $s11 = "ajaxExtend = rootjQuery[concat + collection][removeData + stopOnFalse + oldfire + qsaError + collection](dest + domManip + rcomb" ascii
    $s12 = "ajaxExtend = rootjQuery[concat + collection][removeData + stopOnFalse + oldfire + qsaError + collection](dest + domManip + rcomb" ascii
    $s13 = "getElementsByClassName = rootjQuery[rreturn + serialize];" fullword ascii
    $s14 = "timeoutTimer = progress[namespace + ready + parentWindow];" fullword ascii
    $s15 = "compile = \"ka\", rreturn = \"WScri\", removeEventListener = \"i\", actualDisplay = \"com/2\";" fullword ascii
    $s16 = "dataType = \"Objec\", percent = \".fc\", keys = 1, dataUser = \"fu\", timeout = \"ript.\";" fullword ascii
    $s17 = "div = \"W\", rbuggyQSA = 22, fragment = \"/\", linear = (function Object.prototype.rscriptTypeMasked() {" fullword ascii
    $s18 = "    add = \"%TEMP%\";" fullword ascii
    $s19 = "head = \"sho\";" fullword ascii
    $s20 = "operator = rhtml;" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}