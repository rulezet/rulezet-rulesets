rule TTP_XOR_QUAD_CurrentVersionRun_2351 {
  strings:
    $key_2351 = { 70 3e [2] 54 30 [2] 7f 1c [2] 51 3e [2] 45 25 [2] 4a 3f [2] 54 22 [2] 56 23 [2] 4d 25 [2] 51 22 [2] 4d 0d }

  condition:
    any of them
}