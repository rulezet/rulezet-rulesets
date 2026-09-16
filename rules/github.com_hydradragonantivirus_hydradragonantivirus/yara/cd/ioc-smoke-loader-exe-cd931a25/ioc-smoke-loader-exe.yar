import "hash"
rule IOC_SMOKE_LOADER_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_SMOKE_LOADER_LAB"
    date_IOC   = "2023-11-14 08:55:41"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "SMOKE_LOADER"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "ea226ab509f8001582cace500f1890df678371771cf7ee1cf1d61f949f201c5e" or
    hash.sha256(0, filesize) == "d2a5bffc667647e9ba8a0d1733f9a27df01af72b9dbc7193031aad4c8853c6e4" or
    hash.sha256(0, filesize) == "22f1911d81e0e2feaf26b7b28208b5cbb68be45c39d5a6630c40047de2446f4e" or
    hash.sha256(0, filesize) == "a6189864b80a674de976bc67a13f42fc6e601f2ea11c446047c84e2d12e120ae" or
    hash.sha256(0, filesize) == "95396f2372d133a24cb6a06307c865f37441cb985baa6ce021387ac7b0a2de91" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}