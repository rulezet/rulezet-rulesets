rule _20160921_06311313c2c91f30b188be9b0f27e37d_20160921_13e37e5857b4_778 {
  meta:
    description = "datamaliciousorder - from files 20160921_06311313c2c91f30b188be9b0f27e37d.js, 20160921_13e37e5857b4357c4b5f40a021143101.js, 20160921_22785a85892e6eb0dbe789a8a528129f.js, 20160921_29976a5f68bbdfe415494e838aef0c3a.js, 20160921_3ca43590701fad2cb827b5edf3989d00.js, 20160921_4319d62667a3ba06f88c6ba9123c871b.js, 20160921_4a2d69f96df0dd4c57fda9e63c804950.js, 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_53ea150fd63a4ef657412c858a71a13e.js, 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js, 20160921_5775da34d70f97a2d7aa3296f909af35.js, 20160921_68596411289b2d10a74a19f9fce4a325.js, 20160921_97fcc16be1aae58b311e71df667be641.js, 20160921_9aa040f4b657816cc001fcf9a33be586.js, 20160921_acebc8ac4559526a5a8de801968bd19f.js, 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js, 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js, 20160921_e0f34764de4fcb908eef371ab4011f31.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js, 20160922_51694f0251fa3f1d7267b3d7973d4097.js, 20160922_92c62e47426236a3598469915ee3dcfe.js, 20160922_abb8cfe456777bb23f3253a5921340d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8ad2d8de7bc2cc77c2b00b8eeb4fd7976cd68790eeb4b6bfd14ad188696ed0"
    hash2       = "bd94ae3a0c3b8dadcaba65cdd5f58ebd19d616ac5679af1b7891e5bf26889265"
    hash3       = "3bd9f1cc39c45e7b6963f5eca04b26ef2eaf9c8005e5a0d5f12e868261ae58ca"
    hash4       = "218bc62c15296caf93128e0a5e06fde374e19fd4150b6c9b1def4d962554ef39"
    hash5       = "ef7c5701a8646e7803463e9a01e4f2e45cd535f2ed7174e97abde991a779b665"
    hash6       = "33e5babd254cb93078c026ebb6beb245e487651597122eb576cf5b870dfbf8ee"
    hash7       = "786d4a5233f100c1ba7f5e820c46309247158a45ed43bd58795f05152dbaecf6"
    hash8       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash9       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"
    hash10      = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"
    hash11      = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"
    hash12      = "52b104c52d9f1461833687ee9fc5da1913610266114cbc0018bf345ee135d662"
    hash13      = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"
    hash14      = "06edaae6cd03c231dca115449fcaf6955b5f70df34983f02383296a412f73538"
    hash15      = "79fe55ec3d2d6dbd854df9676c4565b6a8410e1d94298c2ff2f112036fcfac73"
    hash16      = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash17      = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"
    hash18      = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"
    hash19      = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"
    hash20      = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"
    hash21      = "c424926fb99cca3faf3dda68a4860b770a7f0467803b01fbdf54011c52f56a99"
    hash22      = "d6b6eb713cecae41143fb04e090a4809564a1837f49e53a84e27f0d3b0885df7"
    hash23      = "658f6872a894eb9bcb193b7bf73260e92d4627036eede588553b81333dcf0c30"

  strings:
    $s1  = "000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn" ascii
    $s2  = "rn \"BQb\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s3  = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Mc\";})(),(func" ascii
    $s4  = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"" ascii
    $s5  = "on f000(){return \"EZu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s6  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){ret" ascii
    $s7  = "\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"PTs\";})(),(function " ascii
    $s8  = "00(){return \"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"MOc" ascii
    $s9  = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return" ascii
    $s10 = "urn \"RLk\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Yi\";})(),(fu" ascii
    $s11 = "\"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s12 = "\"RLk\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"TKl\";})(),(funct" ascii
    $s13 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"RLk" ascii
    $s14 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Tb\";})(),(function f000(" ascii
    $s15 = "ction f000(){return \"NBs\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s16 = ")(),(function f000(){return \"Br\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DAp\";})(),(function f000" ascii
    $s17 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return " ascii
    $s18 = "return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"HJm\";})(" ascii
    $s19 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Sj\";})(),(function f000(" ascii
    $s20 = "f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MBb" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}