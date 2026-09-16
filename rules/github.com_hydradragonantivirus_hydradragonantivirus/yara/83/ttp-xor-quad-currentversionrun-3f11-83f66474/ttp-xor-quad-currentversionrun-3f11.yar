rule TTP_XOR_QUAD_CurrentVersionRun_3f11 {
  strings:
    $key_3f11 = { 6c 7e [2] 48 70 [2] 63 5c [2] 4d 7e [2] 59 65 [2] 56 7f [2] 48 62 [2] 4a 63 [2] 51 65 [2] 4d 62 [2] 51 4d }

  condition:
    any of them
}