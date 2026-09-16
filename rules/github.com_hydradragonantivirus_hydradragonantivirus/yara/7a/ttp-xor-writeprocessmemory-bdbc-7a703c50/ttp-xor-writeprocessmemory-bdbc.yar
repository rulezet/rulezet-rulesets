rule TTP_XOR_WriteProcessMemory_bdbc {
  strings:
    $key_bdbc = { ea ce [2] d8 ec [2] de d9 [2] f0 d9 [2] cf c5 }

  condition:
    any of them
}