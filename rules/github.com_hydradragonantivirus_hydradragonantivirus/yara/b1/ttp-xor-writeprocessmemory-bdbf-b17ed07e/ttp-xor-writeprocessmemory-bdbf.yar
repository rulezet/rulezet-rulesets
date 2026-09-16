rule TTP_XOR_WriteProcessMemory_bdbf {
  strings:
    $key_bdbf = { ea cd [2] d8 ef [2] de da [2] f0 da [2] cf c6 }

  condition:
    any of them
}