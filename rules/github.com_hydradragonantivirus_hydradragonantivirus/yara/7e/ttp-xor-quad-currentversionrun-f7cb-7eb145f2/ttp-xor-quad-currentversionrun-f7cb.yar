rule TTP_XOR_QUAD_CurrentVersionRun_f7cb {
  strings:
    $key_f7cb = { a4 a4 [2] 80 aa [2] ab 86 [2] 85 a4 [2] 91 bf [2] 9e a5 [2] 80 b8 [2] 82 b9 [2] 99 bf [2] 85 b8 [2] 99 97 }

  condition:
    any of them
}