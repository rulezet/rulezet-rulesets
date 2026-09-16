rule sig_20170227_a2d5c059dcbb09d5d9cbd886c8fe7b51 {
  meta:
    description = "datamaliciousorder - file 20170227_a2d5c059dcbb09d5d9cbd886c8fe7b51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dada78a8093d0e32095bf0c8eb4be6f88b9516582b764a8b3968ad130c49de09"

  strings:
    $s1  = "//aronse = new uchot(dexfeve((-7, [\"i\"]))[0] + ijyzo((-8, [\"f\"]))[0] + urerf((-5, [\"(\"]))[0] + ofyk((-4, [\"p\"]))[0] + qi" ascii
    $s2  = "function truhyq(ukodfirc) {" fullword ascii
    $s3  = "return (ukodfirc);" fullword ascii
    $s4  = "ufiqzovxivanefolohyciwohjezuwesigoldyrzahfacqezizhuqvodvogqojozyzopuphipbiwybuscedojpunkafumfefucocitocuzbirbadjovsaxsalpapviwdy" ascii
    $s5  = "function ltypi(guzyspy) {" fullword ascii
    $s6  = "function mbiqget(omumdoq) {" fullword ascii
    $s7  = "return (guzyspy);" fullword ascii
    $s8  = " this[zuqcyxu((-2, [\"W\"]))[0] + fjono((-3, [\"S\"]))[0] + tajwu((-7, [\"c\"]))[0] + afcexy((-8, [\"r\"]))[0] + jynili((-6, [\"" ascii
    $s9  = "cmembuqi((-6, [\"i\"]))[0] + emaclax((-2, [\"n\"]))[0] + deni((-2, [\".\"]))[0] + diczyfy((-6, [\"p\"]))[0] + amar((-5, [\"h\"])" ascii
    $s10 = "]))[0] + pmamfe((-7, [\"\\\\\"]))[0] + dpaty((-2, [\"W\"]))[0] + tihti((-2, [\"i\"]))[0] + gyre((-2, [\"n\"]))[0] + cofxyg((-6, " ascii
    $s11 = "function occomle(esdastipb) {" fullword ascii
    $s12 = "function heqatp(meqid) {" fullword ascii
    $s13 = "return (bgacdyhfe);" fullword ascii
    $s14 = "function yxahtapk(afmyrrakx) {" fullword ascii
    $s15 = "return (nufy);" fullword ascii
    $s16 = "return (ogibdiw);" fullword ascii
    $s17 = "function iljok(zytkosu) {" fullword ascii
    $s18 = "function kunwolmi(abvyzez) {" fullword ascii
    $s19 = "function uzkyzco(onyx) {" fullword ascii
    $s20 = "return (yvbego);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}