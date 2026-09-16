rule sig_20160518_c32bd6281cffb989762c35801dd13828 {
  meta:
    description = "datamaliciousorder - file 20160518_c32bd6281cffb989762c35801dd13828.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69b2fde3777aa904b7cd823ee7c17780527d8d813222d2d4dd9dccc124dba3d0"

  strings:
    $s1  = "var patient = [transfiguration, lamentation,campania,  \"\"+\".\"+(\"drunkard\",\"waltz\",\"communities\",\"gained\",\"utils\"," ascii
    $s2  = "weasel = ((\"infantile\", \"compression\", \"housewife\", \"risks\", \"EkdThKgJ\") + \"wfbVVPSiJ\").evangelist2();" fullword ascii
    $s3  = "hazard = ((\"imposed\", \"portcullis\", \"materialism\", \"breakdown\", \"pATlkXa\") + \"CCuJFWJ\").evangelist2();" fullword ascii
    $s4  = "chute = chute+ patient.shift();" fullword ascii
    $s5  = "theorist = ((\"informal\", \"brawny\", \"decoy\", \"slammed\", \"sfnuYMHMvTY\") + \"gaQwKfiRHTi\").evangelist2();" fullword ascii
    $s6  = "String.prototype.evangelist = function () {" fullword ascii
    $s7  = "warranty[patient.shift()](chute, compress, true);" fullword ascii
    $s8  = "String.prototype.evangelist2 = function () {" fullword ascii
    $s9  = "String.prototype.evangelist4 = function() {" fullword ascii
    $s10 = "var compress = 6/6;" fullword ascii
    $s11 = "var stratagem = patient.pop().split(\">\");" fullword ascii
    $s12 = "var patient = [transfiguration, lamentation,campania,  \"\"+\".\"+(\"drunkard\",\"waltz\",\"communities\",\"gained\",\"utils\"," ascii
    $s13 = "ddresses\",\"warehouse\",\"vituperation\",\"worcestershire\",\"rosette\",\"08\"), theorist)] = 0;" fullword ascii
    $s14 = "  versus = [];" fullword ascii
    $s15 = "var oldest = new allie(stratagem[0]);" fullword ascii
    $s16 = "var awful = 0;" fullword ascii
    $s17 = "function lithuania(hereby, jeremy) {" fullword ascii
    $s18 = "var transfiguration = \"QWunadulteratedN0aXZunadulteratedlWE9iaunadulteratedmVjdA=unadulterated=\".evangelist4();" fullword ascii
    $s19 = "transparency = \"_F2_\";" fullword ascii
    $s20 = "var allie = this[patient.shift()];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}