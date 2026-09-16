rule Trojan_Autorun_Backdoor_Hupigon_AAAH_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Backdoor.Hupigon.AAAH_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ed5f1cb9336e9c41de9d2ffea45defe806c32f1dfe6fdc15b8f88e2def2393d"

  strings:
    $s1  = " export laws and regulations.  You must comply with all domestic and international export laws and regulations that apply to the" ascii
    $s2  = " au logiciel, aux services ou au contenu (y compris le code) figurant sur des sites Internet tiers ou dans des programmes tiers}" ascii
    $s3  = "TYPE=\"string\"><Value></Value></Control><Control NAME=\"db_host_javascript\" TYPE=\"string\"><Value></Value></Control><Control " ascii
    $s4  = " au logiciel, aux services ou au contenu (y compris le code) figurant sur des sites Internet tiers ou dans des programmes tiers}" ascii
    $s5  = "use the software for commercial software hosting services}{\\rtlch\\fcs1 \\af37 \\ltrch\\fcs0 \\insrsid8263653 \\hich\\af37\\dbc" ascii
    $s6  = ">.</Value></Control><Control NAME=\"db_output_hyperlink_target\" TYPE=\"string\"><Value>_blank</Value></Control><Control NAME=\"" ascii
    $s7  = "7 \\ltrch\\fcs0 \\b0\\insrsid8263653 \\hich\\af37\\dbch\\af11\\loch\\f37  from Systinternals.com}{\\rtlch\\fcs1 \\ab0\\af37 \\lt" ascii
    $s8  = "\\ltrch\\fcs0 \\insrsid9964378\\charrsid11558388 \\hich\\af37\\dbch\\af11\\loch\\f37 anything related to the software, services," ascii
    $s9  = "lbuilder.aspx}{\\propname ProductVersion}\\proptype30{\\staticval 0}{\\propname MScom}\\proptype11{\\staticval 0}{\\propname Lan" ascii
    $s10 = "<Control NAME=\"db_input_heading_comment_column\" TYPE=\"string\"><Value>Insert your comments below</Value></Control><Control NA" ascii
    $s11 = " software.  These laws include restrictions on destinations, end users and end use.  For additional" fullword ascii
    $s12 = "umberOfCopies}\\proptype30{\\staticval Any number of copies}{\\propname MediaElementsTemplates}\\proptype11{\\staticval 0}{\\pro" ascii
    $s13 = "lect\" STATUS=\"sure\"><Value>Any number of copies</Value></Variable><Variable NAME=\"MediaElementsTemplates\" TYPE=\"boolean\" " ascii
    $s14 = " export laws and regulations.  You must comply with all domestic and international export laws and regulations that apply to the" ascii
    $s15 = "\\b\\lang1033\\langfe1033\\loch\\f37\\hich\\af37\\dbch\\af11\\langnp1033\\langfenp1033 \\sbasedon10 \\slocked Heading 2 Char;}{" ascii
    $s16 = "\\fs19\\lang1033\\langfe1033\\loch\\f37\\hich\\af37\\dbch\\af11\\cgrid\\langnp1033\\langfenp1033 \\sbasedon0 \\snext9 heading 9;" ascii
    $s17 = "ed\"/><Variable NAME=\"ProductVersion\" TYPE=\"string\" STATUS=\"sure\"><Value>0</Value></Variable><Variable NAME=\"MScom\" TYPE" ascii
    $s18 = "\\sbasedon0 \\snext6 heading 6;}{\\s7\\ql \\fi-357\\li2506\\ri0\\sb120\\sa120\\widctlpar\\jclisttab\\tx2509\\wrapdefault\\aspalp" ascii
    $s19 = "\\b\\fs19\\lang1033\\langfe1033\\loch\\f37\\hich\\af37\\dbch\\af11\\cgrid\\langnp1033\\langfenp1033 \\sbasedon0 \\snext1 heading" ascii
    $s20 = "\\proptype30{\\staticval No transfer permitted}{\\propname OtherMicrosoftPrograms}\\proptype11{\\staticval 0}{\\propname Prerele" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}