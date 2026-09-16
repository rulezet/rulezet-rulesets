rule TTP_XOR_QUAD_CurrentVersionRun_e2ee {
  strings:
    $key_e2ee = { b1 81 [2] 95 8f [2] be a3 [2] 90 81 [2] 84 9a [2] 8b 80 [2] 95 9d [2] 97 9c [2] 8c 9a [2] 90 9d [2] 8c b2 }

  condition:
    any of them
}