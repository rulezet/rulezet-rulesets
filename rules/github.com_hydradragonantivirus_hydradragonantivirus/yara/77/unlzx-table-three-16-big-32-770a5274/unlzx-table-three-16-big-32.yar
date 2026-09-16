rule unlzx_table_three__16_big_32_ {
  strings:
    $a0 = { 00 00 00 01 00 03 00 07 00 0f 00 1f 00 3f 00 7f 00 ff 01 ff 03 ff 07 ff 0f ff 1f ff 3f ff 7f ff }

  condition:
    $a0
}