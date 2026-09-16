rule TTP_XOR_WriteProcessMemory_ba9d {
  strings:
    $key_ba9d = { ed ef [2] df cd [2] d9 f8 [2] f7 f8 [2] c8 e4 }

  condition:
    any of them
}