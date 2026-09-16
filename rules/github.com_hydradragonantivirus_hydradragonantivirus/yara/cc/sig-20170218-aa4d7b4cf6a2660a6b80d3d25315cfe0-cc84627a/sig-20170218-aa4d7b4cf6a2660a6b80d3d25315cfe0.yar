rule sig_20170218_aa4d7b4cf6a2660a6b80d3d25315cfe0 {
  meta:
    description = "datamaliciousorder - file 20170218_aa4d7b4cf6a2660a6b80d3d25315cfe0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3100251a1b2eb6c36e3c0e83724fa0136b6d1db96c42d40b6aebaaca7e47082c"

  strings:
    $s1  = "wxaxvalt = axluvfu[0] + sjumxinru[0] + zovuwx[2] + alpohk[1] + uligac[1] + detojpe[0] + nkipnyqz[1] + lotali[3] + wukroq[1] + er" ascii
    $s2  = "var mist = [Number(1), [Number(3), Number(6), Number(5), WScript][3], Number(2), Number(7)][1][kyngesh](vohi);" fullword ascii
    $s3  = "var nhirite = [Number(1), [Number(3), Number(6), Number(5), WScript][3], Number(2), Number(7)][1][kyngesh](esigxer);" fullword ascii
    $s4  = "var getu = [Number(2), \"$ovo\", Number(6), Number(4)];" fullword ascii
    $s5  = "var axluvfu = [\"cmd.\", Number(1)];" fullword ascii
    $s6  = "+ dzoxi[0] + hjinvyjgo[0] + hifu[0] + etcezwy[0] + ohipt[1] + pyzfe[0] + itsyfa[0] + ifysy[0] + cfizcuh[0] + tkyrpoq[1] + kaka[2" ascii
    $s7  = "var arezku = [\"run\", Number(1), Number(6), Number(6)];" fullword ascii
    $s8  = "var exbinkocq = [\"mo='\", Number(1), Number(4), Number(4)];" fullword ascii
    $s9  = "var comokv = [\"utu=\", Number(6), Number(1)];" fullword ascii
    $s10 = "var geca = [\"GetB\", Number(5)];" fullword ascii
    $s11 = "var ctaqpapj = [\"o+$e\", Number(9), Number(9), Number(4)];" fullword ascii
    $s12 = "var fhoxmo = [Number(2), \"+$us\"];" fullword ascii
    $s13 = "var hifu = [\"'^ec\", Number(6), Number(4), Number(9)];" fullword ascii
    $s14 = "var uligac = [Number(8), \"rshe\"];" fullword ascii
    $s15 = "var janazs = [Number(5), \"doxr\", Number(6), Number(4)];" fullword ascii
    $s16 = "var wukroq = [Number(3), \"='^.\"];" fullword ascii
    $s17 = "var pefide = [Number(2), \" S';\"];" fullword ascii
    $s18 = "var usrasy = [\"';$i\", Number(8)];" fullword ascii
    $s19 = "var ncecro = [\"$rac\", Number(4)];" fullword ascii
    $s20 = "var spowily = [\"drov\", Number(7), Number(7)];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}