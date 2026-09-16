rule _20161216_4406464846d3d1b62f2fc2ae7a3e3ecd_20161216_5d326c19fe43_2585 {
  meta:
    description = "datamaliciousorder - from files 20161216_4406464846d3d1b62f2fc2ae7a3e3ecd.js, 20161216_5d326c19fe43a154de06ee416df03173.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "662a392f3e8bc57b61b7787745b430fb2dbf9e91bfbdc76b03a4a35ac7afb48d"
    hash2       = "db7a361f75f7c895dcd095a632364455526cd1257e75bf876ffee61ed4a6ed06"

  strings:
    $s1 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFk0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s2 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFk0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s3 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFk0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s4 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFk0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s5 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFk0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFk0(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s7 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFk0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s8 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFk0(\"\"))), 1);///////////////////////////////////////////////" ascii

  condition:
    (uint16(0) == 0x7566 and (all of them)
    ) or (all of them)
}