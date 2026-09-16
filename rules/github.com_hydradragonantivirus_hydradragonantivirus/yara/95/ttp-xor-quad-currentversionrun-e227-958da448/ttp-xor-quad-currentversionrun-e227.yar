rule TTP_XOR_QUAD_CurrentVersionRun_e227 {
  strings:
    $key_e227 = { b1 48 [2] 95 46 [2] be 6a [2] 90 48 [2] 84 53 [2] 8b 49 [2] 95 54 [2] 97 55 [2] 8c 53 [2] 90 54 [2] 8c 7b }

  condition:
    any of them
}