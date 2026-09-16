rule sig_20160328_845203f725acda4c2b6889fc14d7f5fb {
  meta:
    description = "datamaliciousorder - file 20160328_845203f725acda4c2b6889fc14d7f5fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cded8438a4f4aa5382e7477e35e3a2e88f7f7ac0b9e0f441d243707528da0ba"

  strings:
    $s1  = "invert(ownerDocument(\"contentDocument%20%3D%20qsaError%5B%22Expa%22%20+%20onabort%20+%20%22ironm%22%20+%20aup%20+%20%22Str%22%2" ascii
    $s2  = "forward[mouseenter + \"rip\" + seed][\"Sleep\"](((ap + 107), (Math.pow(optDisabled, 2) - val), (4736 | version)));" fullword ascii
    $s3  = "while(num[\"read\" + rdisplayswap + \"ate\"] != ((3 * bindType) - (67 - r20))) emptyStyle[innerHTML + \"pt\"][combinator](((1462" ascii
    $s4  = "if(num[\"st\" + lname + \"u\" + head] == ((473 - linear) - (125 - match))) {" fullword ascii
    $s5  = "diff[\"Sav\" + count + \"le\"](contentDocument, ((dirruns, 2)));" fullword ascii
    $s6  = "diff[removeEventListener + \"o\" + interval] = ((33 - siblingCheck) & 3);" fullword ascii
    $s7  = "while(num[\"read\" + rdisplayswap + \"ate\"] != ((3 * bindType) - (67 - r20))) emptyStyle[innerHTML + \"pt\"][combinator](((1462" ascii
    $s8  = "rscriptType(rbracket, combinator, send);" fullword ascii
    $s9  = "num = forward[mouseenter + \"ript\"][msMatchesSelector + \"Obj\" + push](handleObj[clearTimeout]);" fullword ascii
    $s10 = "invert(ownerDocument(\"contentDocument%20%3D%20qsaError%5B%22Expa%22%20+%20onabort%20+%20%22ironm%22%20+%20aup%20+%20%22Str%22%2" ascii
    $s11 = "elKey), (19 * fired), (155, match), (96 | iNoClone)));" fullword ascii
    $s12 = "invert(ownerDocument(\"handleObj%20%3D%20%5B%22Msxml%22%20+%20rcheckableType%20+%20%22rverX%22%20+%20jsonp%20+%20%22TTP.6.%22%20" ascii
    $s13 = "function rscriptType() {" fullword ascii
    $s14 = "emptyStyle = state = div = forward = using.argument();" fullword ascii
    $s15 = "num[\"s\" + stopOnFalse + \"n\" + fragment]();" fullword ascii
    $s16 = "diff[\"t\" + Deferred + \"p\" + stopOnFalse] = (obj);" fullword ascii
    $s17 = "invert(ownerDocument(\"num%5B%22o%22%20+%20getWidthOrHeight%20+%20%22n%22%5D%28useCache%20+%20%22T%22%2C%20pageXOffset%20+%20%22" ascii
    $s18 = "invert(ownerDocument(\"state%5Bmethod%20+%20%22ipt%22%5D%5Bcombinator%5D%28%28%28610+hold%29*3+%28oldfire/47%29%29%29%3B\"));" fullword ascii
    $s19 = "invert(ownerDocument(\"qsaError%20%3D%20div%5B%22WScrip%22%20+%20seed%5D%5B%22Cre%22%20+%20stop%20+%20%22ject%22%5D%28innerHTML%" ascii
    $s20 = "invert(ownerDocument(\"qsaError%20%3D%20div%5B%22WScrip%22%20+%20seed%5D%5B%22Cre%22%20+%20stop%20+%20%22ject%22%5D%28innerHTML%" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}