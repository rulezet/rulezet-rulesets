rule TTP_XOR_QUAD_CurrentVersionRun_3afe {
  strings:
    $key_3afe = { 69 91 [2] 4d 9f [2] 66 b3 [2] 48 91 [2] 5c 8a [2] 53 90 [2] 4d 8d [2] 4f 8c [2] 54 8a [2] 48 8d [2] 54 a2 }

  condition:
    any of them
}