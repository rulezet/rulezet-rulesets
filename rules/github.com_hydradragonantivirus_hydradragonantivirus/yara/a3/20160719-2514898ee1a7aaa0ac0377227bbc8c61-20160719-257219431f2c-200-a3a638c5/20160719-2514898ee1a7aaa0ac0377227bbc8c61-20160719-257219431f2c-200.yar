rule _20160719_2514898ee1a7aaa0ac0377227bbc8c61_20160719_257219431f2c_200 {
  meta:
    description = "datamaliciousorder - from files 20160719_2514898ee1a7aaa0ac0377227bbc8c61.js, 20160719_257219431f2cae1567a0a1ca3010c112.js, 20160719_446525488303f8807114ca28cfed2501.js, 20160719_463e8c8f4f0252919825b100f5cf30bc.js, 20160719_5b509f1aa17f7990e342081299626da6.js, 20160719_743ac90452e37ee573157be121a26d13.js, 20160719_9ce478f458813f7f8bb7af2c72ae2e83.js, 20160719_a09640e24ce2f627cfe816f95608a1a3.js, 20160719_aa6251d4ed416a363df90be9077a7410.js, 20160719_ca40637ca5b787229b187ea44550bd0f.js, 20160719_d0aa336522605714bc587563484acab4.js, 20160719_d7b5b9ba33e88c4e22a1a4c4ac6f23f8.js, 20160719_db7b40c2e4d28747099a1b1bc729b526.js, 20160719_e91b5e63063c83fff6d5ad299d242e59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9852f6dfa605a7648ff5257f6cee3f8343515387bc38f0bb6fd654dcc6380fe1"
    hash2       = "0672641c31cf0afb2d3727d89846d061df7abc7806c25798d636db6d2931cf56"
    hash3       = "e4394d96652cee80ec08efdc5fff65883b5e928873a289dc7c014a1045768879"
    hash4       = "d272d18fcd2d36197671fd293eaa871f04b5bedf339c1666a607c51af5ee1911"
    hash5       = "fcd55bda981d82732b5ec56e700d77d1bff45b1f500f6973cc95c9f41d8e5cb3"
    hash6       = "87d22c4169014c6c4a0ea37c5692b103c4357a0fd31e86138a22f3ca60f11890"
    hash7       = "f076d7b9fe393bcadeac147bc76335880feeb11e14c72f031d45076d1b12345e"
    hash8       = "2af5a091f8c0ed284f76f85b99254515c9de311f7558e085d84870eeaaa386df"
    hash9       = "c350c323cfe611f1af9fa263027de380d758284cf26bd6b6ef3eff1ec734fb39"
    hash10      = "95ccf89c01b4fee4fc8adfd35d46104cdc48eac94f1ed8e8253f9861bbc3bbc1"
    hash11      = "d1e07530a0df49b1aa6dc78c68baa27f11e9e560580d69baac293f2239e6beae"
    hash12      = "9256763572c4a9f4f132a40dfb02efca6e9d0a10084ef7ffd9f5208ab435c76a"
    hash13      = "54f3f076463ba66002d21612df19cb5d8452c253cef72879308a95234d01ea4b"
    hash14      = "48e66a25a1c79ea9d888b4a3b5222d04bb41bbbe7b7cbe05995be5e25237494d"

  strings:
    $s1  = "var ibribritqrthGfnbvtqrth_PRigund = new Array(-1, -1, -1, -1, -1, -1,-1,-1);" fullword ascii
    $s2  = "if ((!ibribritqrthGfnbvtqrth_check || !object[ibribritqrthGfnbvtqrth_property]) && typeof object.prototype[ibribritqrthGfnbvtqrt" ascii
    $s3  = "String.prototype.ibribritqrthGfnbvtqrth_center2 = function () {" fullword ascii
    $s4  = "if ((!ibribritqrthGfnbvtqrth_check || !object[ibribritqrthGfnbvtqrth_property]) && typeof object.prototype[ibribritqrthGfnbvtqrt" ascii
    $s5  = "    return new ibribritqrthGfnbvtqrth_weirshtrasse(ibribritqrthGfnbvtqrth_param1.x - ibribritqrthGfnbvtqrth_param2.x, ibribritqr" ascii
    $s6  = "    return new ibribritqrthGfnbvtqrth_weirshtrasse(ibribritqrthGfnbvtqrth_param1.x - ibribritqrthGfnbvtqrth_param2.x, ibribritqr" ascii
    $s7  = "String.prototype.ibribritqrthGfnbvtqrth_center4 = function() {" fullword ascii
    $s8  = "        } while (ibribritqrthGfnbvtqrth_i < ibribritqrthGfnbvtqrth_len && ibribritqrthGfnbvtqrth_c1 == -1);" fullword ascii
    $s9  = "} catch (ibribritqrthGfnbvtqrth_RFXuYwO) {WScript.echo(ibribritqrthGfnbvtqrth_RFXuYwO.message);" fullword ascii
    $s10 = "        } while (ibribritqrthGfnbvtqrth_i < ibribritqrthGfnbvtqrth_len && ibribritqrthGfnbvtqrth_c4 == -1);" fullword ascii
    $s11 = "        } while (ibribritqrthGfnbvtqrth_i < ibribritqrthGfnbvtqrth_len && ibribritqrthGfnbvtqrth_c3 == -1);" fullword ascii
    $s12 = "var ibribritqrthGfnbvtqrth_Native = function(options){" fullword ascii
    $s13 = "ibribritqrthGfnbvtqrth_weirshtrasse.ibribritqrthGfnbvtqrth_sameOrN = function(ibribritqrthGfnbvtqrth_param1, ibribritqrthGfnbvtq" ascii
    $s14 = "var ibribritqrthGfnbvtqrth_ZumZum = this[ibribritqrthGfnbvtqrth_DoUtra_NO];" fullword ascii
    $s15 = "ibribritqrthGfnbvtqrth_weirshtrasse.create = function(){" fullword ascii
    $s16 = "ibribritqrthGfnbvtqrth_weirshtrasse.ibribritqrthGfnbvtqrth_subtract = function(ibribritqrthGfnbvtqrth_param1, ibribritqrthGfnbvt" ascii
    $s17 = "ibribritqrthGfnbvtqrth_Native.ibribritqrthGfnbvtqrth_typize = function(object, ibribritqrthGfnbvtqrth_family){" fullword ascii
    $s18 = "function ibribritqrthGfnbvtqrth_Shtyler4(ibribritqrthGfnbvtqrth_gutter, ibribritqrthGfnbvtqrth_StrokaParam2) {" fullword ascii
    $s19 = " function ibribritqrthGfnbvtqrth_center(ibribritqrthGfnbvtqrth_rivulet) {" fullword ascii
    $s20 = "ibribritqrthGfnbvtqrth_weirshtrasse.angle = function(ibribritqrthGfnbvtqrth_p) {" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}