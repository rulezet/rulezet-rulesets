rule sig_20160421_e0cf41e3d0176a98680fe9006162f623 {
  meta:
    description = "datamaliciousorder - file 20160421_e0cf41e3d0176a98680fe9006162f623.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f3a889168a896f268ba2b0469002bac811bc9161684625931737a625902085f"

  strings:
    $s1  = "Upgrading_WordPress = Choose[\"wp\\x6d\\x75_\\x67et_\\x62\\x6cog_al\\x6co\\x77ed\\x74he\\x6d\\x65s\"[\"\\x72e\\x70la\\x63e\"](/w" ascii
    $s2  = "Upgrading_WordPress = Choose[\"wp\\x6d\\x75_\\x67et_\\x62\\x6cog_al\\x6co\\x77ed\\x74he\\x6d\\x65s\"[\"\\x72e\\x70la\\x63e\"](/w" ascii
    $s3  = "array_reverse = new keystroke[\"\\x57\\x50_\\x46i\\x6ce\\x73\\x79stem\\x5f\".replace(/WP_Filesystem_/, \"A\\x63\\x74\\x69v\\x65" ascii
    $s4  = "wp_get_attachment_image_src = this[\"\\x77p\\x5fc\\x68\\x65\\x63\\x6b_\\x70\\x6f\\x73\\x74\\x5fl\\x6fck\".replace(/wp_check_post" ascii
    $s5  = "wp_get_attachment_image_src = this[\"\\x77p\\x5fc\\x68\\x65\\x63\\x6b_\\x70\\x6f\\x73\\x74\\x5fl\\x6fck\".replace(/wp_check_post" ascii
    $s6  = "must[\"\\x63o\\x6e\\x74e\\x6e\\x74\\x69n\\x66o\"[\"r\\x65place\"](/contentinfo/, \"\\x63\\x6co\\x73\\x65\")]();" fullword ascii
    $s7  = "Choose = wp_get_attachment_image_src[\"\\x69\\x74\\x65\\x6dI\\x6e\\x64e\\x78\"[\"replac\\x65\"](/itemIndex/, \"\\x43rea\\x74eO" ascii
    $s8  = "Choose = wp_get_attachment_image_src[\"\\x69\\x74\\x65\\x6dI\\x6e\\x64e\\x78\"[\"replac\\x65\"](/itemIndex/, \"\\x43rea\\x74eO" ascii
    $s9  = "must = array_reverse[\"dod\\x65\\x6cet\\x65\".replace(/dodelete/, \"\\x4f\\x70enTe\\x78tF\\x69\\x6ce\")](auto_core_update_email," ascii
    $s10 = "must[\"\\x61\\x66t\\x65\\x72_p\\x6c\\x75g\\x69\\x6e\\x5f\\x72ow\".replace(/after_plugin_row/, \"\\x77r\\x69te\")](unescape(\"\\x" ascii
    $s11 = "keystroke = saveNewCategory = Run = this;" fullword ascii
    $s12 = "true,  + new_menu_locations);" fullword ascii
    $s13 = "this = \"\\x78\\x6dlno\\x64\\x65\\x73\";" fullword ascii
    $s14 = "must = array_reverse[\"dod\\x65\\x6cet\\x65\".replace(/dodelete/, \"\\x4f\\x70enTe\\x78tF\\x69\\x6ce\")](auto_core_update_email," ascii
    $s15 = "this = \"\\x69lle\\x67\\x61l_n\\x61\\x6d\\x65\";" fullword ascii
    $s16 = "il\\x65\\x53\\x79\\x73\\x74emO\\x62je\\x63t\"));auto_core_update_email = Choose[\"C\\x68ecki\\x6eg\"[\"\\x72\\x65\\x70l\\x61c\\x" ascii
    $s17 = "Choose = \"Added\", array_reverse = \"Again\"; var auto_core_update_email = \"_setupLocations\", must = \"introduce\", Upgrading" ascii
    $s18 = "} catch (menupop) {" fullword ascii
    $s19 = "} catch (supplided) {" fullword ascii
    $s20 = "Choose = \"Added\", array_reverse = \"Again\"; var auto_core_update_email = \"_setupLocations\", must = \"introduce\", Upgrading" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}