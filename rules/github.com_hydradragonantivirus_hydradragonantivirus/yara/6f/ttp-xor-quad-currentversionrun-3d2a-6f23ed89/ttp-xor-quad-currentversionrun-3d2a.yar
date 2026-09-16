rule TTP_XOR_QUAD_CurrentVersionRun_3d2a {
  strings:
    $key_3d2a = { 6e 45 [2] 4a 4b [2] 61 67 [2] 4f 45 [2] 5b 5e [2] 54 44 [2] 4a 59 [2] 48 58 [2] 53 5e [2] 4f 59 [2] 53 76 }

  condition:
    any of them
}