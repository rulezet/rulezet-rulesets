rule sig_20160325_47bad15f161dbfc299dc3ad793649412 {
  meta:
    description = "datamaliciousorder - file 20160325_47bad15f161dbfc299dc3ad793649412.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0bd784547bdd202826447a63cafb36c038a05d44ffe2979d65ce97301e72015"

  strings:
    $s1  = "hold = isEmptyObject[\"Expand\" + implicitRelative + \"ronmen\" + get + \"gs\"](combinator + \"%/\") + wrapMap + \"atc\" + overw" ascii
    $s2  = "hold = isEmptyObject[\"Expand\" + implicitRelative + \"ronmen\" + get + \"gs\"](combinator + \"%/\") + wrapMap + \"atc\" + overw" ascii
    $s3  = "function processData() {" fullword ascii
    $s4  = "target = \"protot\";" fullword ascii
    $s5  = "attributes = \"WScrip\", unique = \"http:\", now = \"rit\", subtract = 173;" fullword ascii
    $s6  = "var combinator = \"%TEMP\"," fullword ascii
    $s7  = "isEmptyObject = etag[\"Crea\" + last + \"bject\"](attributes + \"t.She\" + has);" fullword ascii
    $s8  = "getAll = \"Sleep\", clone = 8, originalEvent = \"xe\", implicitRelative = \"Envi\";" fullword ascii
    $s9  = "getAttributeNode = \"en\", propFilter = (function mappedTypes() {}, \"ep\"), createInputPseudo = 11, onload = \"/Zc0\";" fullword ascii
    $s10 = "   var args = [][\"con\" + callbackInverse + \"tor\"][target + \"ype\"][location + \"or\" + delegate][\"a\" + bySet + \"y\"]();" fullword ascii
    $s11 = "   wrapAll[delegate + \"y\" + getText] = ((fnOver, 23, rmouseEvent, 1) & (currentValue / 31));" fullword ascii
    $s12 = "function readyList() {" fullword ascii
    $s13 = "function gotoEnd(ridentifier, andSelf, documentIsHTML, initial) {" fullword ascii
    $s14 = "function completeDeferred() {" fullword ascii
    $s15 = "readyList(clone);" fullword ascii
    $s16 = "   value[\"clo\" + compiled]();" fullword ascii
    $s17 = "} catch(requestHeaders) {}" fullword ascii
    $s18 = "   copyIsArray(location, camel, parentsUntil, setOffset, target);" fullword ascii
    $s19 = "function iterator() {" fullword ascii
    $s20 = "function cssPrefixes() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}