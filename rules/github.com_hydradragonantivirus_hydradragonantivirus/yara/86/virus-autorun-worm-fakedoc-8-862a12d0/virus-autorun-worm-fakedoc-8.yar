rule Virus_Autorun_Worm_FakeDoc_8 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Worm.FakeDoc_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a69af7cedf84534ed6addf7cf92aef46b61a6f1dd4ac946e97b17f42811c86f"

  strings:
    $s1  = "\\mintLim0\\mnaryLim1}{\\info{\\author User}{\\operator User}{\\creatim\\yr2024\\mo3\\dy14\\hr10\\min10}{\\revtim\\yr2024\\mo3" ascii
    $s2  = "}{\\version3}{\\edmins0}{\\nofpages2}{\\nofwords504}{\\nofchars4070}{\\*\\company Reanimator Extreme Edition}{\\nofcharsws4565}" fullword ascii
    $s3  = "\\mintLim0\\mnaryLim1}{\\info{\\author User}{\\operator User}{\\creatim\\yr2024\\mo3\\dy14\\hr10\\min10}{\\revtim\\yr2024\\mo3" ascii
    $s4  = "\\ltrch\\fcs0 \\fs22\\lang1049\\langfe1049\\loch\\f31506\\hich\\af31506\\dbch\\af31505\\cgrid\\langnp1049\\langfenp1049 \\snext0" ascii
    $s5  = "\\snext11 \\ssemihidden \\sunhideused \\sqformat Normal Table;}{\\*\\cs15 \\additive \\rtlch\\fcs1 \\af0 \\ltrch\\fcs0 \\ul\\cf2" ascii
    $s6  = "\\snext11 \\ssemihidden \\sunhideused \\sqformat Normal Table;}{\\*\\cs15 \\additive \\rtlch\\fcs1 \\af0 \\ltrch\\fcs0 \\ul\\cf2" ascii
    $s7  = "{\\f45\\fbidi \\froman\\fcharset178\\fprq2 Times New Roman (Arabic);}{\\f46\\fbidi \\froman\\fcharset186\\fprq2 Times New Roman " ascii
    $s8  = "iority0 \\styrsid16123076 Normal;}{\\*\\cs10 \\additive \\ssemihidden \\sunhideused \\spriority1 Default Paragraph Font;}{\\*" fullword ascii
    $s9  = "{\\f39\\fbidi \\froman\\fcharset238\\fprq2 Times New Roman CE;}{\\f42\\fbidi \\froman\\fcharset161\\fprq2 Times New Roman Greek;" ascii
    $s10 = "{\\f39\\fbidi \\froman\\fcharset238\\fprq2 Times New Roman CE;}{\\f42\\fbidi \\froman\\fcharset161\\fprq2 Times New Roman Greek;" ascii
    $s11 = "PAD{\\rtf1\\adeflang1025\\ansi\\ansicpg1251\\uc1\\adeff31507\\deff0\\stshfdbch31505\\stshfloch31506\\stshfhich31506\\stshfbi0\\d" ascii
    $s12 = "di \\froman\\fcharset162\\fprq2 Times New Roman Tur;}{\\f44\\fbidi \\froman\\fcharset177\\fprq2 Times New Roman (Hebrew);}" fullword ascii
    $s13 = "et204\\fprq2{\\*\\panose 02020603050405020304}Times New Roman;}{\\f41\\fbidi \\froman\\fcharset0\\fprq2 Times New Roman;}" fullword ascii
    $s14 = "\\froman\\fcharset162\\fprq2 Cambria Math Tur;}{\\f386\\fbidi \\froman\\fcharset186\\fprq2 Cambria Math Baltic;}" fullword ascii
    $s15 = "{\\f379\\fbidi \\froman\\fcharset238\\fprq2 Cambria Math CE;}{\\f382\\fbidi \\froman\\fcharset161\\fprq2 Cambria Math Greek;}{" ascii
    $s16 = "{\\f417\\fbidi \\fswiss\\fcharset163\\fprq2 Calibri (Vietnamese);}{\\flomajor\\f31510\\fbidi \\froman\\fcharset0\\fprq2 Times Ne" ascii
    $s17 = "{\\f45\\fbidi \\froman\\fcharset178\\fprq2 Times New Roman (Arabic);}{\\f46\\fbidi \\froman\\fcharset186\\fprq2 Times New Roman " ascii
    $s18 = "{\\f34\\fbidi \\froman\\fcharset204\\fprq2{\\*\\panose 02040503050406030204}Cambria Math;}{\\f37\\fbidi \\fswiss\\fcharset204\\f" ascii
    $s19 = "{\\f387\\fbidi \\froman\\fcharset163\\fprq2 Cambria Math (Vietnamese);}{\\f411\\fbidi \\fswiss\\fcharset0\\fprq2 Calibri;}{\\f40" ascii
    $s20 = "f47\\fbidi \\froman\\fcharset163\\fprq2 Times New Roman (Vietnamese);}{\\f381\\fbidi \\froman\\fcharset0\\fprq2 Cambria Math;}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}