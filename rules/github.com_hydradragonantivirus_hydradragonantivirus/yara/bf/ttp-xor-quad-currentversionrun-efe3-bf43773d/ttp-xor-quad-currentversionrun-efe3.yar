rule TTP_XOR_QUAD_CurrentVersionRun_efe3 {
  strings:
    $key_efe3 = { bc 8c [2] 98 82 [2] b3 ae [2] 9d 8c [2] 89 97 [2] 86 8d [2] 98 90 [2] 9a 91 [2] 81 97 [2] 9d 90 [2] 81 bf }

  condition:
    any of them
}