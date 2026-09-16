rule TTP_XOR_QUAD_CurrentVersionRun_e23d {
  strings:
    $key_e23d = { b1 52 [2] 95 5c [2] be 70 [2] 90 52 [2] 84 49 [2] 8b 53 [2] 95 4e [2] 97 4f [2] 8c 49 [2] 90 4e [2] 8c 61 }

  condition:
    any of them
}