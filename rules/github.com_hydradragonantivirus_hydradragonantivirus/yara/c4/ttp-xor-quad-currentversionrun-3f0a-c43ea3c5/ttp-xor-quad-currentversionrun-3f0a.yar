rule TTP_XOR_QUAD_CurrentVersionRun_3f0a {
  strings:
    $key_3f0a = { 6c 65 [2] 48 6b [2] 63 47 [2] 4d 65 [2] 59 7e [2] 56 64 [2] 48 79 [2] 4a 78 [2] 51 7e [2] 4d 79 [2] 51 56 }

  condition:
    any of them
}