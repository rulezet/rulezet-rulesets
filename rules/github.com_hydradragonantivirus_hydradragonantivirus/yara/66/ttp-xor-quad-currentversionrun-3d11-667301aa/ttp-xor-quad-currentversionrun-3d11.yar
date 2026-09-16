rule TTP_XOR_QUAD_CurrentVersionRun_3d11 {
  strings:
    $key_3d11 = { 6e 7e [2] 4a 70 [2] 61 5c [2] 4f 7e [2] 5b 65 [2] 54 7f [2] 4a 62 [2] 48 63 [2] 53 65 [2] 4f 62 [2] 53 4d }

  condition:
    any of them
}