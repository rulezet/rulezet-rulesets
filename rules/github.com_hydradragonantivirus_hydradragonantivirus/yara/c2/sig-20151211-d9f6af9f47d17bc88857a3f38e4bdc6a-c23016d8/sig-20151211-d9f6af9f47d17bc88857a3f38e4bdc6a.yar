rule sig_20151211_d9f6af9f47d17bc88857a3f38e4bdc6a {
  meta:
    description = "datamaliciousorder - file 20151211_d9f6af9f47d17bc88857a3f38e4bdc6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fe1c27d447bb06aa8741298009cceb87da9e6474bdc74f0f4938d2a796dc83d"

  strings:
    $s1  = "function uraJGmn(zuChPQIVcjOXJjtiDFZffHmYDbZVSXKdNXzl) {return !isNaN(parseFloat(zuChPQIVcjOXJjtiDFZffHmYDbZVSXKdNXzl)) && isFin" ascii
    $s2  = "function uraJGmn(zuChPQIVcjOXJjtiDFZffHmYDbZVSXKdNXzl) {return !isNaN(parseFloat(zuChPQIVcjOXJjtiDFZffHmYDbZVSXKdNXzl)) && isFin" ascii
    $s3  = "hniUujBf[zdOtzEcqxMk]=(-809+809)/987; while(true) { if(NhniUujBf[zdOtzEcqxMk] > kmkNS[zdOtzEcqxMk].length-(-512+529)/17) { break" ascii
    $s4  = "var o=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5a\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s5  = "function UOpPErdDaaQ(xibmRpVB,JxQZFB){return xibmRpVB.split(JxQZFB)}" fullword ascii
    $s6  = "function kphHXsNONGGnJvDhD(kmkNS){CfJDFWFMoQC= '';zdOtzEcqxMk=(-153+153)/611; while(true){if(zdOtzEcqxMk >= (247+25)/136)break;N" ascii
    $s7  = "++;}zdOtzEcqxMk++;} return CfJDFWFMoQC}" fullword ascii
    $s8  = "function mvGmk(WSgYcopBOQu,cXuEMXQOBYErm,oldOMSGQ){BaxE=parseInt(WSgYcopBOQu,cXuEMXQOBYErm);slYeL=BaxE.toString(oldOMSGQ);return" ascii
    $s9  = "function rsgSkaqBWqaMlXaktZoJqvskFLOlGvjDDIXpHNmbMsEyaPpphxylVZ(wCuntMfuZnwxS,wiWghcYZWvxFEI){ return MtlSg[mvGmk(wCuntMfuZnwxS[" ascii
    $s10 = "var J=new Array(\"28\",\"2e\",\"2a\",\"29\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s11 = "function rsgSkaqBWqaMlXaktZoJqvskFLOlGvjDDIXpHNmbMsEyaPpphxylVZ(wCuntMfuZnwxS,wiWghcYZWvxFEI){ return MtlSg[mvGmk(wCuntMfuZnwxS[" ascii
    $s12 = "function kphHXsNONGGnJvDhD(kmkNS){CfJDFWFMoQC= '';zdOtzEcqxMk=(-153+153)/611; while(true){if(zdOtzEcqxMk >= (247+25)/136)break;N" ascii
    $s13 = "var o=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5a\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s14 = "var J=new Array(\"28\",\"2e\",\"2a\",\"29\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s15 = " slYeL;}function AfXbBZVGJmUMokw(jttSpXuhCatBijKjF){eval(jttSpXuhCatBijKjF)}" fullword ascii
    $s16 = "function mvGmk(WSgYcopBOQu,cXuEMXQOBYErm,oldOMSGQ){BaxE=parseInt(WSgYcopBOQu,cXuEMXQOBYErm);slYeL=BaxE.toString(oldOMSGQ);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}