rule TTP_XOR_QUAD_CurrentVersionRun_0a11 {
  strings:
    $key_0a11 = { 59 7e [2] 7d 70 [2] 56 5c [2] 78 7e [2] 6c 65 [2] 63 7f [2] 7d 62 [2] 7f 63 [2] 64 65 [2] 78 62 [2] 64 4d }

  condition:
    any of them
}