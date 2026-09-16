import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_216_Troja_109 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_216.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_303.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_313.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_540.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_305_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_351_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_359_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_420_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_487_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_549_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_560_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_563_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_566_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.o8Z@aCkwazk_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d690b62919e34f7c74665621eee20836169966a53cba0d96febffd4878b687b1"
    hash2       = "707e591168ed85c7eacba103dd9f0297d178c5c503325ab0c5bcac2fcfb3d8f5"
    hash3       = "cb8afdf63dff57a5ab081658abdd76d45d53efcb9b59f7c38f955677214eecfc"
    hash4       = "189a77a0029218c43883302ec0ac6cb9cbba6648f79452d0f2f73fa4d5de77c0"
    hash5       = "a897c6a5d99635069f6136caae87b131dc6425ba9755fc6453864d729653f81d"
    hash6       = "98ca76867be454b37c8a244cd43c0754e2e18f9b46edc388dde31ac838f80f6c"
    hash7       = "11fbdbce752b003d79bf1c966d1c222506ca90f7fab89bea112a8832cf86f741"
    hash8       = "3ace686d0bb9ce94f2186d4bf76413038ae1a3b7e886270a1a23c724a7b3940d"
    hash9       = "0cab86d19d0c15fbd515e6e43c1f55ef9ec40b997abcd0f2b2d7546ab55984f2"
    hash10      = "f946d792ce2c4715f8fff82b3b673e1fedee309112514b6bbf1226b1132ca831"
    hash11      = "950de1a495c8e44c870fe7eaa93d54a1c1a1d101ca8a8e4d71561627e861fb74"
    hash12      = "5e4eeb0a060fc80f0c986ce11b043deb8057b9f5e60a63bffcf4327a2628b942"
    hash13      = "02238763bf882d1a6fe488e5d5c988b2ad6db2a9bc1b9be2c1c1308e64ace5a0"
    hash14      = "52dd965c0918c84a43339927c0cf16bed01360717abcc6db8d7a75e681a2544b"

  strings:
    $s1  = "his document is a Microsoft Word template for IEEE Transactions on Magnetics. Use of this document as a template is optional. If" ascii
    $s2  = " them to files. First, download a PostScript printer driver from " fullword ascii
    $s3  = "d processor or LaTeX (the general IEEE LaTeX template is available at " fullword ascii
    $s4  = "These instructions give you guidelines for preparing papers for IEEE Transactions on Magnetics. Use this document as a template " ascii
    $s5  = "IEEE has partnered with SPi Publisher Services to offer pre-submission professional editing services to IEEE authors. SPi copyed" ascii
    $s6  = "Also upload a file with complete contact information for all authors. Include full mailing addresses, telephone numbers, fax num" ascii
    $s7  = "r and usage prior to submitting their manuscripts for review or during the review process can go to " fullword ascii
    $s8  = "If you have a scanner, a quick way to prepare figure files is to print your figures on paper exactly as you want them to appear," ascii
    $s9  = "Authors of regular and conference-related papers should prepare their papers for review using Microsoft Word and this template o" ascii
    $s10 = " you are reading a paper version of this document, please download the electronic file, transmag2015.doc, from " fullword ascii
    $s11 = " to submit a manuscript for copyediting. A link is provided on the Manuscript Central Web site. SPi copyeditors will edit for gr" ascii
    $s12 = " printer definition. In Word, paste your figure into a new document. Print to a file using the PostScript printer driver. File n" ascii
    $s13 = "There are 7 stages (screens) to the submission process; you must complete all 7 for a complete submission. At the end of each st" ascii
    $s14 = "There are 7 stages (screens) to the submission process; you must complete all 7 for a complete submission. At the end of each st" ascii
    $s15 = " printer definition. In Word, paste your figure into a new document. Print to a file using the PostScript printer driver. File n" ascii
    $s16 = "You will be asked to file an electronic copyright form during the submission process. (Authors are responsible for obtaining any" ascii
    $s17 = "Most authors will be able to prepare images in one of the allowed formats listed above. This section provides optional, addition" ascii
    $s18 = "You will be asked to file an electronic copyright form during the submission process. (Authors are responsible for obtaining any" ascii
    $s19 = "Authors may prepare their papers for review using any word processor, one or two columns, single or double spaced. Please follow" ascii
    $s20 = "Authors may prepare their papers for review using any word processor, one or two columns, single or double spaced. Please follow" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "1a611a7df1f3828b0157c4725145a721" and (8 of them)
    ) or (all of them)
}