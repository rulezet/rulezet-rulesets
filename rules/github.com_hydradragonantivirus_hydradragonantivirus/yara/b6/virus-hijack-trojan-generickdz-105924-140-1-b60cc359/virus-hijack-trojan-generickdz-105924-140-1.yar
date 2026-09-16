rule Virus_Hijack_Trojan_GenericKDZ_105924_140_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_140_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00169bddf9e9803502d64a34a1344407e8cda4a9933834452fea7522a213763b"

  strings:
    $s1 = "Puru^Panavivul wave fetabalejetepab kukuyi dopumogez soketevo pobayokupe jadu niteyajimi cegebapuke" fullword wide
    $s2 = "Yare feg" fullword wide
    $s3 = "RizefusevovaWFas belodopatugiye sejox vamidacotopayor sinew rineh yerumugolucexu wabokaj zuvodujemuj;Cekutopifuxeli wotimosetahi" wide
    $s4 = "Bade pitegatepopep" fullword wide
    $s5 = "Wite mifowiyuj gefuwoxoyujete" fullword wide
    $s6 = "[Sefol budegajaliwe rixunikuceyuron wani rizeze dade xajo roburuzivociye kojehovazawajaw ser" fullword wide
    $s7 = "Zogo howekub yel" fullword wide
    $s8 = "Vinobese vowifak kojonor cumuTRepewijimuru suf gunidomezilazoc janisikuva jimamiy bojawopuceh dacob tofus weha poh.Kepusukajawid" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}