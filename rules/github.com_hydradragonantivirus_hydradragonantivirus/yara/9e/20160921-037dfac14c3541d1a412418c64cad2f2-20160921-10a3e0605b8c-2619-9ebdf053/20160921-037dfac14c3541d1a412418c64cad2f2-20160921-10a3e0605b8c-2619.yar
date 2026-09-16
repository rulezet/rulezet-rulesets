rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_10a3e0605b8c_2619 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_4ad5ed78dc05b02005f65ab785b9c74a.js, 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js, 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js, 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160921_cff7808833d9e819d4a4f10450848a81.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js, 20160922_7706788d60398ea7d883afb2532d218f.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash3       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash4       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash5       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash6       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash7       = "7e5f9d362688f19111d3dbdf393d51e133fcc63eb7db27536cb31d1205ccc9e3"
    hash8       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash9       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"
    hash10      = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"
    hash11      = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash12      = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash13      = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash14      = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash15      = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"
    hash16      = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"
    hash17      = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"
    hash18      = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"
    hash19      = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"
    hash20      = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"
    hash21      = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1 = "n\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s2 = "f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"SG" ascii
    $s3 = "ction f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){retur" ascii
    $s4 = "eturn \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"RPt\";})()" ascii
    $s5 = "tion f000(){return \"Nv\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s6 = "{return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DNa\";})" ascii
    $s7 = "Aa\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TKl\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}