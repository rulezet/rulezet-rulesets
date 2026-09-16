rule TTP_XOR_QUAD_CurrentVersionRun_3f26 {
  strings:
    $key_3f26 = { 6c 49 [2] 48 47 [2] 63 6b [2] 4d 49 [2] 59 52 [2] 56 48 [2] 48 55 [2] 4a 54 [2] 51 52 [2] 4d 55 [2] 51 7a }

  condition:
    any of them
}