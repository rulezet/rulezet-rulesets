rule sig_20160311_42d2a6e1d51d73074f17a47ebdc2429f {
  meta:
    description = "datamaliciousorder - file 20160311_42d2a6e1d51d73074f17a47ebdc2429f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81eda13b9c4c875db04f732ba7aeed4bb01cc5bcb60ecd358b9beac315c42b45"

  strings:
    $s1  = "hasDuplicate[speeds + \"p\" + cssHooks + \"n\"](rnamespace + \"T\".w(), specialEasing + \"p://\" + readyWait + \"211.19\" + oMat" ascii
    $s2  = "node = (((214 - tweener) - (Math.pow(16, srcElements) - 232)), ((fadeTo + 9) | (Math.pow(responseText, 2) - dataShow)), eval(\"t" ascii
    $s3  = "node = (((214 - tweener) - (Math.pow(16, srcElements) - 232)), ((fadeTo + 9) | (Math.pow(responseText, 2) - dataShow)), eval(\"t" ascii
    $s4  = "e)) - ((512 | funescape) | (11209 * mouseleave + 2353))) / ((srcElements * 2 | (left * 5 + get)) & ((33 - tr) | 5 * srcElements " ascii
    $s5  = "finalValue = node[getAll + \"t\"];" fullword ascii
    $s6  = "parseXML[\"R\" + xml](dataType.w(((bool) | (210 - nType))), (0 / (disabled * 2 + tfoot)), 0);" fullword ascii
    $s7  = "insertAfter[\"sav\" + elemData + \"e\"](dataType, ((156 - mouseenter), (204 - select), (3 & srcElements)));" fullword ascii
    $s8  = "* 2)))) == wait));" fullword ascii
    $s9  = "test = finalValue[shift + \"Obje\" + grep](\"WScri\".w() + clientLeft + \"She\" + rhash);" fullword ascii
    $s10 = "dataType = test[\"Expan\" + compilerCache + \"iron\".w() + beforeSend + \"trin\" + a](\"%TE\" + startLength) + \"innerT\".w() + " ascii
    $s11 = "pipe = \"ext\"," fullword ascii
    $s12 = "dataType = test[\"Expan\" + compilerCache + \"iron\".w() + beforeSend + \"trin\" + a](\"%TE\" + startLength) + \"innerT\".w() + " ascii
    $s13 = "qualifier = \"pt\", getJSON = \"/89o8i\", tr = 19, attrNames = 109, beforeSend = \"mentS\";" fullword ascii
    $s14 = "scrollTo = 48, compilerCache = \"dEnv\", get = 4, clientLeft = \"pt.\", left = 5, disabled = 8;" fullword ascii
    $s15 = "insertAfter = node[\"WScri\".w() + qualifier][\"Crea\" + sortOrder + \"bjec\" + step](\"ADO\".w() + inPage + \"eam\");" fullword ascii
    $s16 = "function readyList() {" fullword ascii
    $s17 = "hasDuplicate = node[buildFragment + \"ipt\".w()][expand + \"eObj\" + has](\"MSXM\" + jQuery + \"LHTTP\".w());" fullword ascii
    $s18 = "scrollTop = \"wr\", isReady = 4602, tfoot = (function String.prototype.w() {" fullword ascii
    $s19 = "function fadeIn() {" fullword ascii
    $s20 = "function tweeners() {" fullword ascii

  condition:
    uint16(0) == 0x7572 and
    8 of them
}