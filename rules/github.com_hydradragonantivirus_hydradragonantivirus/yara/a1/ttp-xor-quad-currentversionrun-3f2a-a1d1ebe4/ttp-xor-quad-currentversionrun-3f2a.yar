rule TTP_XOR_QUAD_CurrentVersionRun_3f2a {
  strings:
    $key_3f2a = { 6c 45 [2] 48 4b [2] 63 67 [2] 4d 45 [2] 59 5e [2] 56 44 [2] 48 59 [2] 4a 58 [2] 51 5e [2] 4d 59 [2] 51 76 }

  condition:
    any of them
}