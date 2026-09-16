rule _20161216_6da64982566975c0ef40fc8c9c1d79f2_20161216_9cbc1f54ad26_2586 {
  meta:
    description = "datamaliciousorder - from files 20161216_6da64982566975c0ef40fc8c9c1d79f2.js, 20161216_9cbc1f54ad26a0af9ca6755322d54c73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c9c20be97e62f615b3c5a279d0daad97f58922d706c8c2abac9ad22195f3ef5"
    hash2       = "48efd06576711a3a9e997440c75d5c4e14fd7da4d0520dab985764e52a85df80"

  strings:
    $s1 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIk5(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s2 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIk5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s3 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIk5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s4 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIk5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s5 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIk5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIk5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s7 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIk5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s8 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIk5(\"\"))), 1);///////////////////////////////////////////////" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}