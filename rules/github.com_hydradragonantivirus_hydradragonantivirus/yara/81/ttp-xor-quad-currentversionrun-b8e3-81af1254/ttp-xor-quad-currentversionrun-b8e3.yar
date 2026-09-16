rule TTP_XOR_QUAD_CurrentVersionRun_b8e3 {
  strings:
    $key_b8e3 = { eb 8c [2] cf 82 [2] e4 ae [2] ca 8c [2] de 97 [2] d1 8d [2] cf 90 [2] cd 91 [2] d6 97 [2] ca 90 [2] d6 bf }

  condition:
    any of them
}