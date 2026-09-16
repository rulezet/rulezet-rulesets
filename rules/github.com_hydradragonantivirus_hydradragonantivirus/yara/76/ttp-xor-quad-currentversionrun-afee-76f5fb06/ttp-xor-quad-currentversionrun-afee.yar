rule TTP_XOR_QUAD_CurrentVersionRun_afee {
  strings:
    $key_afee = { fc 81 [2] d8 8f [2] f3 a3 [2] dd 81 [2] c9 9a [2] c6 80 [2] d8 9d [2] da 9c [2] c1 9a [2] dd 9d [2] c1 b2 }

  condition:
    any of them
}