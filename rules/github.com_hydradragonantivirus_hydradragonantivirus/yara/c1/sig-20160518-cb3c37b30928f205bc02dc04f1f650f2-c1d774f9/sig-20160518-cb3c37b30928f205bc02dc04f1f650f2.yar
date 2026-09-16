rule sig_20160518_cb3c37b30928f205bc02dc04f1f650f2 {
  meta:
    description = "datamaliciousorder - file 20160518_cb3c37b30928f205bc02dc04f1f650f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "820d8a36f09e66ea81d7045e35d77a70c114e15c793594da97396b91442ed7cb"

  strings:
    $s1  = "var anthropology = [fossil, dedication,sheriff,  \"\"+\".\"+(\"financier\",\"rochester\",\"kernel\",\"regarding\",\"totally\",\"" ascii
    $s2  = "compatriot = compatriot+ anthropology.shift();" fullword ascii
    $s3  = "salem[anthropology.shift()](compatriot, troupe, true);" fullword ascii
    $s4  = "var horse = anthropology.pop().split(\">\");" fullword ascii
    $s5  = "var anthropology = [fossil, dedication,sheriff,  \"\"+\".\"+(\"financier\",\"rochester\",\"kernel\",\"regarding\",\"totally\",\"" ascii
    $s6  = "        displaying[(unconstitutional + \"o\"+(\"stating\",\"accounts\",\"mapped\",\"credulity\",\"ghent\",\"ports\",\"drover\"," ascii
    $s7  = "var displacement = this[anthropology.shift()];" fullword ascii
    $s8  = "var trellis = salem[anthropology.shift()](anthropology.shift());" fullword ascii
    $s9  = "        displaying[(unconstitutional + \"o\"+(\"stating\",\"accounts\",\"mapped\",\"credulity\",\"ghent\",\"ports\",\"drover\"," ascii
    $s10 = "unconstitutional = ((\"stretcher\", \"rugby\", \"flowers\", \"patrick\", \"pSGcPVLDEQg\") + \"urGeHGSbMkz\").plain2();" fullword ascii
    $s11 = "weasel = ((\"younger\", \"gymnastic\", \"formal\", \"moved\", \"EqusfUAMPP\") + \"FvmitH\").plain2();" fullword ascii
    $s12 = "String.prototype.plain4 = function() {" fullword ascii
    $s13 = "var passageway = {" fullword ascii
    $s14 = "String.prototype.plain2 = function () {" fullword ascii
    $s15 = "for (var i in passageway){ukraine = ukraine.replace(i, passageway[i]);}" fullword ascii
    $s16 = "String.prototype.plain = function () {" fullword ascii
    $s17 = "            damaging[synthetic]((\"singapore\",\"forceful\",\"G\" + weasel) + (\"uptodate\",\"active\",\"outrun\",\"cornish\",\"" ascii
    $s18 = "            damaging[synthetic]((\"singapore\",\"forceful\",\"G\" + weasel) + (\"uptodate\",\"active\",\"outrun\",\"cornish\",\"" ascii
    $s19 = "        var compatriot = trellis + \"/\" + objectives ;" fullword ascii
    $s20 = "var fossil = \"QWputrefactionN0aXZputrefactionlWE9iaputrefactionmVjdA=putrefaction=\".plain4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}