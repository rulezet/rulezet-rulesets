rule sig_20160313_c71d1aa86975306f4ce95956972015c3 {
  meta:
    description = "datamaliciousorder - file 20160313_c71d1aa86975306f4ce95956972015c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41ded88b604cf847a85e59adfa3b424939f277560bf44a36ce768460ce97cb2f"

  strings:
    $s1  = "return bzlWRck[0] + bzlWRck[2] + bzlWRck[4] + \".F\" + bzlWRck[7] + bzlWRck[9] + bzlWRck[12] + bzlWRck[14];" fullword ascii
    $s2  = "var Da = true  , DfeZ = DXc[7] + DXc[9] + DXc[11];" fullword ascii
    $s3  = "var bzlWRck = \"Sc UUydECo r jZrKFYaIm ipting dVWVfaK yKI ile HYgkecVbjMfjRI System mv gaZze Obj oFOydj ect VAXIzlK\".split(\" " ascii
    $s4  = "REOeB.open(lalIY,LBKIQ,false);" fullword ascii
    $s5  = "if(E>=F.length) {break;}" fullword ascii
    $s6  = "function vSOfKlj(Rukc) {" fullword ascii
    $s7  = "function UEZkZTIkO() {" fullword ascii
    $s8  = "if (G >= ZcCzn.length) {break;}" fullword ascii
    $s9  = "return PLa.size;" fullword ascii
    $s10 = "function rzFeiIpK() {" fullword ascii
    $s11 = "function XtxMkzTMC(YsZhSNzJsYE) {" fullword ascii
    $s12 = "function QAgNEVPa(PLa) {" fullword ascii
    $s13 = "function SRPuX(AXMTNz) {" fullword ascii
    $s14 = "return Rukc.responseBody;" fullword ascii
    $s15 = "function YkbC(QOAcT) {" fullword ascii
    $s16 = "function bhwzLVJ(VGOj,BerPv) {" fullword ascii
    $s17 = "function yOty(IrTzY,RQjwC) {" fullword ascii
    $s18 = "function XWrB(hWhAV) {" fullword ascii
    $s19 = "function jORJ(QblAL) {" fullword ascii
    $s20 = "return MFPjN;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}