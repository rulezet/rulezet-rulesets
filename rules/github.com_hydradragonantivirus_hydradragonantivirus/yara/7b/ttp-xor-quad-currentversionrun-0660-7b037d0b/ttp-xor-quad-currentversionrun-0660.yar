rule TTP_XOR_QUAD_CurrentVersionRun_0660 {
  strings:
    $key_0660 = { 55 0f [2] 71 01 [2] 5a 2d [2] 74 0f [2] 60 14 [2] 6f 0e [2] 71 13 [2] 73 12 [2] 68 14 [2] 74 13 [2] 68 3c }

  condition:
    any of them
}