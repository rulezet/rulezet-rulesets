rule TTP_XOR_QUAD_CurrentVersionRun_26e3 {
  strings:
    $key_26e3 = { 75 8c [2] 51 82 [2] 7a ae [2] 54 8c [2] 40 97 [2] 4f 8d [2] 51 90 [2] 53 91 [2] 48 97 [2] 54 90 [2] 48 bf }

  condition:
    any of them
}