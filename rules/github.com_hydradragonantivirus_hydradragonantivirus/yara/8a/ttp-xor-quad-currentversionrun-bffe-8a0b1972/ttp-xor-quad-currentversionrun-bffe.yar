rule TTP_XOR_QUAD_CurrentVersionRun_bffe {
  strings:
    $key_bffe = { ec 91 [2] c8 9f [2] e3 b3 [2] cd 91 [2] d9 8a [2] d6 90 [2] c8 8d [2] ca 8c [2] d1 8a [2] cd 8d [2] d1 a2 }

  condition:
    any of them
}