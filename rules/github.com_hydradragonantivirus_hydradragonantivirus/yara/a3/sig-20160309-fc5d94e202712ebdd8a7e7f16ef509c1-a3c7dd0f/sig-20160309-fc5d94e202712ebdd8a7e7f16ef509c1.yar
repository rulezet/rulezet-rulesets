rule sig_20160309_fc5d94e202712ebdd8a7e7f16ef509c1 {
  meta:
    description = "datamaliciousorder - file 20160309_fc5d94e202712ebdd8a7e7f16ef509c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d78a8bcc8c928d777bc53f5faaf5975e2bcf2d116befe6fc58d3ef79f87dd7d"

  strings:
    $s1  = "var fW = true  , qwqG = CUv[7] + CUv[9] + CUv[11];" fullword ascii
    $s2  = "return fnKuOsE[0] + fnKuOsE[2] + fnKuOsE[4] + \".F\" + fnKuOsE[7] + fnKuOsE[9] + fnKuOsE[12] + fnKuOsE[14];" fullword ascii
    $s3  = "var fnKuOsE = \"Sc uPTTmoN r Mrdnssflo ipting IrbFZdN rQR ile zWzhvNoBIefnzu System wh IpNRb Obj osdDuH ect mlSaDai\".split(\" " ascii
    $s4  = "ijrEY.open(kXjkU,QRnur,false);" fullword ascii
    $s5  = "var CUv = (\"2.XMLHTTP WkYOJwi wslSG XML ream St VVWqFlft AD TVFobFe O Fnjy D\").split(\" \");" fullword ascii
    $s6  = "function ilFTb(AqifAb) {" fullword ascii
    $s7  = "return vqQft.status;" fullword ascii
    $s8  = "return mcNZ.responseBody;" fullword ascii
    $s9  = "function JTWzFGH(mcNZ) {" fullword ascii
    $s10 = "IE = 1;zEC.position=(279-279);bIDe(zEC,/*iBRT551dlc*/nYEK/*Q9FZ18AmpS*/+qFRlkdS+PDz[7]+PDz[9]+PDz[11]); try  {" fullword ascii
    $s11 = "return QDVEJYY(Po,iulIv[314-308]+iulIv[295-288]+iulIv[500-492]);" fullword ascii
    $s12 = "function QuVs(jmWwc) {" fullword ascii
    $s13 = "function OQmf(rmlqe) {" fullword ascii
    $s14 = "return nkf.size;" fullword ascii
    $s15 = "if(W>=t.length) {break;}" fullword ascii
    $s16 = "function TWeu(vqQft) {" fullword ascii
    $s17 = "function VLaAaySn() {" fullword ascii
    $s18 = "return VhQKWqq" fullword ascii
    $s19 = "function QDVEJYY(JPtF,jACCc) {" fullword ascii
    $s20 = "function USYyDzJOg(DUqvTjbaFmx) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}