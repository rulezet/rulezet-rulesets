import "hash"
rule Owncloud {
  condition:
    
    hash.sha1(0, filesize) == "a58489a3d8401295bb09cfbad09486f605625658" or      hash.sha1(0, filesize) == "463627a4064dc05e93e6f9fc5605d4c8a4e09200" or      hash.sha1(0, filesize) == "5346cb6817a75c26a6aad86e0b4ffb1d5145caa5" or      hash.sha1(0, filesize) == "c8a6d4292448c7996e0092e6bfd38f90c34df090" or      hash.sha1(0, filesize) == "acc7af31d4067c336937719b9a9ad7ac8497561e"  }