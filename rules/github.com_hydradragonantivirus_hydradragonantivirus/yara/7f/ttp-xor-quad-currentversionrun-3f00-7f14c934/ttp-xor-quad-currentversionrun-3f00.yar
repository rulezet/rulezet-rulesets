rule TTP_XOR_QUAD_CurrentVersionRun_3f00 {
  strings:
    $key_3f00 = { 6c 6f [2] 48 61 [2] 63 4d [2] 4d 6f [2] 59 74 [2] 56 6e [2] 48 73 [2] 4a 72 [2] 51 74 [2] 4d 73 [2] 51 5c }

  condition:
    any of them
}