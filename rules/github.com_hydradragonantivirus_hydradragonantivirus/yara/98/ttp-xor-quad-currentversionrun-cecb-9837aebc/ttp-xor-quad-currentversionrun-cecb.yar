rule TTP_XOR_QUAD_CurrentVersionRun_cecb {
  strings:
    $key_cecb = { 9d a4 [2] b9 aa [2] 92 86 [2] bc a4 [2] a8 bf [2] a7 a5 [2] b9 b8 [2] bb b9 [2] a0 bf [2] bc b8 [2] a0 97 }

  condition:
    any of them
}